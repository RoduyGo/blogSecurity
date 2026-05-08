---
title: "Tổng quan Windows Event Logs và kỹ năng lọc log bằng PowerShell XML"
description: "Khám phá 'camera an ninh' của Windows: Event Logs. Tổng hợp các Event ID sinh tử dành cho SOC Analyst"
date: 2026-05-08T12:00:00+07:00
math: false
license:
comments: true
draft: false
categories:
    - Security
    - SOC Analytics
    - Incident Response
tags:
    - event-logs
    - powershell
    - xml
    - xpath
    - threat-hunting
build:
    list: always
---

Chào mừng các bạn quay trở lại với Series Giải phẫu Windows OS & SOC Analytics! Bất kỳ một tên trộm nào khi đột nhập cũng sẽ cố gắng xóa dấu vết, trốn tránh camera. Trong hệ điều hành Windows, "camera an ninh" đó chính là Event Logs (Nhật ký sự kiện). Mã độc có thể ẩn mình dưới lớp vỏ bọc `svchost.exe` hay lách qua UAC, nhưng mọi hành động của chúng đều để lại những "gợn sóng" trong nhật ký hệ thống. Hôm nay, chúng ta sẽ học cách đọc hiểu các Event ID sinh tử và sử dụng PowerShell kết hợp XML để truy vết hacker với tốc độ ánh sáng!

## 1. Tổng quan về Windows Event Logs

Event Logs là nơi lưu trữ mọi "nhịp đập" của máy tính. Bất kể là bạn cắm một chiếc USB, cài một phần mềm, khởi động dịch vụ hay gõ sai mật khẩu, Windows đều ghi chép lại một cách tỉ mỉ.

### 1.1 Phân loại Nhật ký (Log Types)

Hệ thống phân chia nhật ký thành nhiều nhánh để dễ quản lý:
- **System (Hệ thống):** Ghi lại các sự kiện liên quan đến hệ điều hành, thay đổi phần cứng, khởi động/tắt máy và hoạt động của trình điều khiển (Driver).
- **Security (Bảo mật):** Đây là mỏ vàng của SOC. Ghi lại các sự kiện Đăng nhập/Đăng xuất (Logon/Logoff), thay đổi quyền hạn và quản lý người dùng.
- **Application (Ứng dụng):** Ghi lại lỗi phần mềm (crash), cảnh báo từ các ứng dụng cài đặt trên máy.

### 1.2 Mức độ Sự kiện (Event Levels)

Mỗi sự kiện được gắn một mức độ nghiêm trọng:
- **Information:** Hoạt động bình thường, thành công.
- **Warning:** Có vấn đề tiềm tàng nhưng chưa làm sập chức năng (ví dụ: ổ đĩa sắp đầy).
- **Error:** Vấn đề nghiêm trọng (mất dữ liệu, phần mềm bị crash).
- **Success/Failure Audit:** Cực kỳ quan trọng trong nhánh Security, ghi nhận các nỗ lực truy cập tài nguyên (đăng nhập đúng hoặc sai pass).

> **Góc nhìn SOC - Cấu hình dung lượng Log:** Mặc định, file log (như `Security.evtx`) bị giới hạn dung lượng (thường là 20MB) và được cấu hình ghi đè sự kiện cũ nhất (Overwrite events as needed). Hacker hiểu điều này, chúng có thể "xả rác" (Spam logs) để đẩy các log độc hại trôi đi mất. Do đó, trên các máy chủ quan trọng, quản trị viên thường phải chỉnh thành cấu hình **Archive the log when full** (Nén lại khi đầy) để không mất dấu vết lịch sử.

## 2. Từ điển Event ID "Gối đầu giường" của SOC

Để săn tìm mã độc, bạn không thể đọc từng dòng log một. Bạn phải thuộc lòng những Event ID (EID) mang tính "chỉ điểm" sau đây:

### 2.1 Nhóm Application (Ứng dụng)
- **EID 1000 (Application Error):** Phần mềm bị treo cứng và tự đóng. Nếu một dịch vụ quan trọng (như `lsass.exe`) liên tục báo lỗi 1000, có thể hacker đang dùng tool dump bộ nhớ bị lỗi.
- **EID 11724 (MsiInstaller):** Thông báo một phần mềm vừa bị gỡ bỏ. Nếu phần mềm bị gỡ là Antivirus, đây là báo động đỏ cực độ (Red Flag)!

### 2.2 Nhóm System (Hệ thống)
- **EID 12 / 13:** Máy tính bắt đầu Boot (12) và Tắt máy bình thường (13).
- **EID 7040:** Thay đổi loại khởi động của một dịch vụ (ví dụ: bật lại một dịch vụ từ Disable sang Auto).
- **EID 7045:** Một dịch vụ (Service) mới vừa được cài đặt. Hacker cực kỳ thích cài "Backdoor" dưới dạng một Service để tự chạy ngầm cùng quyền LocalSystem.

### 2.3 Nhóm Security (Bảo mật) - Trái tim của SOC
- **EID 4624 (Logon Success):** Đăng nhập thành công. Cần soi kỹ Logon Type (Type 2 là ngồi gõ trực tiếp, Type 3 là qua mạng/Share, Type 10 là Remote Desktop).
- **EID 4625 (Logon Failure):** Gõ sai pass. Nếu EID này xuất hiện dồn dập hàng loạt với nhiều user khác nhau, bạn đang đối mặt với tấn công Password Spraying hoặc Brute Force.
- **EID 4672 (Special Logon):** Phiên đăng nhập được gán đặc quyền Admin (SYSTEM). Nếu một tài khoản người dùng thường (như nhân viên lễ tân) có log này, họ đã leo quyền (Privilege Escalation) thành công.
- **EID 4720 (User Created) & 4732 (Added to Group):** Hacker tạo tài khoản Backdoor mới và nhét nó vào nhóm Administrators. Mọi sự kiện 4732 tác động vào nhóm Admin đều phải được điều tra lập tức.
- **EID 4688 (Process Creation):** Ghi nhận một tiến trình/câu lệnh mới vừa chạy. Kết hợp dòng log này, ta biết chính xác mã độc đã gõ lệnh gì trên CMD/PowerShell.
- **EID 1102 (Log Cleared):** Nhật ký an ninh đã bị xóa trắng. Dấu vết lẩn trốn rõ ràng nhất.


## 3. Giải phẫu cấu trúc XML của một Sự kiện

Mở giao diện Event Viewer (Friendly View) và bấm xem bằng mắt thường rất dễ hiểu, nhưng lại quá chậm để tự động hóa. Thực chất, giao diện này chỉ là bản "dịch" lại từ ngôn ngữ lưu trữ gốc của Windows: XML.

Chuyển sang tab **XML View**, bạn sẽ thấy một sự kiện luôn chia làm 2 khối chính:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <!-- KHỐI SYSTEM: Chứa siêu dữ liệu chung -->
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" ... />
    <EventID>4672</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-02-02T17:22:57.0339579Z" />
    <Execution ProcessID="1504" ThreadID="1600" />
    <Computer>NguyenDuy</Computer>
  </System>
  
  <!-- KHỐI EVENT DATA: Phần "thịt" chứa thông tin điều tra -->
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
    SeSecurityPrivilege
    SeTakeOwnershipPrivilege
    SeDebugPrivilege
    SeImpersonatePrivilege</Data>
  </EventData>
</Event>
```

**Tại sao phải quan tâm XML?** Bởi vì những thông tin sinh tử như Tên tài khoản (`SubjectUserName`) hay Đặc quyền (`PrivilegeList`) được giấu sâu bên trong các node `<Data>`. Nếu bạn hiểu cấu trúc này, bạn có thể viết script lọc ra chính xác các đăng nhập mờ ám có đặc quyền `SeDebugPrivilege` (đặc quyền cho phép can thiệp bộ nhớ, cực kỳ nguy hiểm, thường dùng để dump mật khẩu `lsass.exe`).

## 4. Kỹ năng lọc log thực chiến bằng PowerShell (XPath)

Event Viewer rất nặng và chậm khi load hàng chục GB logs. Thay vào đó, SOC Analyst sử dụng PowerShell với Cmdlet `Get-WinEvent` kết hợp cú pháp truy vấn XPath để quét logs trong chớp mắt.

### 4.1 Thống kê nhanh bằng Wevtutil

Để đếm tổng số tệp nhật ký trên máy mà không cần mở giao diện đồ họa, bạn có thể dùng lệnh:

```cmd
wevtutil.exe el | find /c /v ""
```
*(Lệnh này liệt kê tất cả các log `el` và đếm tổng số dòng)*

### 4.2 Săn tìm mã độc với Get-WinEvent & XPath

Giả sử bạn nghi ngờ có kẻ đang liệt kê danh sách nhóm cục bộ (Event ID 4798) để tìm nhóm Admin. Thay vì cuộn chuột thủ công, hãy ném cú pháp XPath này vào PowerShell:

```powershell
# Lọc toàn bộ Log Security, chỉ lấy các sự kiện có Event ID = 4798
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4798)]]"
```
**Nâng cao hơn: Lọc dựa trên EventData (Dữ liệu bên trong)** 
Nếu bạn muốn tìm đích danh Log Logon thất bại (EID 4625) nhưng chỉ lọc các lần thất bại có mã lỗi `0xC0000064` (Tên người dùng không tồn tại - Dấu hiệu của việc dò quét tài khoản), bạn có thể viết Rule XPath truy vấn thẳng vào lớp `<EventData>`:

```powershell
# Tìm các log đăng nhập sai (4625) với mã lỗi (Status) là 0xC0000064
$Query = "*[System[EventID=4625] and EventData[Data[@Name='Status']='0xc0000064']]"
Get-WinEvent -LogName Security -FilterXPath $Query | Select-Object TimeCreated, Message
```

Sức mạnh của XPath cho phép các nhà phân tích SOC trích xuất hàng triệu sự kiện (Events) chỉ trong vài giây, và đây cũng chính là cơ sở cốt lõi để xây dựng các tập luật (Rules) tự động cho hệ thống SIEM (như Wazuh hay Splunk).

---

*Như vậy, chúng ta đã nắm trong tay cách hệ điều hành "ghi sổ" mọi biến động. Bằng cách làm chủ các mã Event ID và kỹ thuật lọc XML bằng PowerShell, bạn đã biến mình từ một người bị động trở thành một "thợ săn" (Threat Hunter) chủ động đi tìm những bất thường trên hệ thống. Ở bài viết tới, chúng ta sẽ tìm hiểu về cách kết hợp Event Logs với Sysmon (System Monitor) – một công cụ biến nhật ký Windows thành hệ thống giám sát cấp độ quân sự. Đừng bỏ lỡ nhé!*
