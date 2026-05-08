---
title: "Bài 14: Sysmon (Phần 2) - Truy vết Fileless Malware, Timestomping qua Event ID 3, 10, 11"
description: "Nâng cao kỹ năng Threat Hunting với Sysmon. Khám phá cách giải mã các kỹ thuật lẩn tránh tinh vi của hacker như Fileless Malware, Timestomping và Process Injection thông qua các Event ID 3, 10 và 11."
date: 2026-05-09T18:00:00+07:00
image: "cover-sysmon-part2.jpg"  # (Tùy chọn) Tên ảnh bìa của bài viết
math: false         
license:            
comments: true      
draft: false        
categories:
    - Security
    - SOC Analytics
    - Threat Hunting
tags:
    - sysmon
    - fileless-malware
    - timestomping
    - dfir
    - process-injection
build:
    list: always
---
Chào mừng các bạn quay trở lại với Phần 2 của loạt bài về Sysmon trong Series Giải phẫu Windows OS & SOC Analytics! Ở phần trước, chúng ta đã dùng Event ID 1 để "bắt thóp" mã độc dựa vào mã Hash. Nhưng nếu mã độc không tồn tại dưới dạng file trên ổ cứng thì sao? Nếu chúng chạy thẳng trên RAM, hoặc âm thầm chọc ngoáy vào tiến trình hệ thống để ăn cắp mật khẩu? Hôm nay, chúng ta sẽ mở khóa sức mạnh thực sự của Sysmon với bộ 3 Event ID sinh tử: 3, 10 và 11 để chống lại những kỹ thuật lẩn tránh (Evasion) tinh vi nhất.
1. Event ID 10 (Process Access): "Kính lúp" soi bộ nhớ và Fileless Malware
Trong hệ điều hành Windows, các tiến trình (Process) vốn dĩ nằm trong các không gian bộ nhớ biệt lập. Tuy nhiên, mã độc thường xuyên tìm cách "chọc" vào vùng nhớ của các tiến trình hệ thống hợp lệ để ăn cắp dữ liệu hoặc tiêm mã độc (Process Injection) nhằm che giấu hành vi.
Đây là lúc Sysmon Event ID 10 (Process Access) tỏa sáng. Trong khi Windows mặc định dùng Event ID 4656 nhưng rất khó cấu hình, Sysmon EID 10 cung cấp bức tranh rõ nét về việc tiến trình nào đang đòi quyền truy cập vào tiến trình nào
.
Đặc biệt, EID 10 là "khắc tinh" của hai hành vi sau:
Dump mật khẩu LSASS: Hacker thường nhắm vào tiến trình lsass.exe để trích xuất mật khẩu. EID 10 sẽ cảnh báo ngay nếu một file lạ xin quyền truy cập vào lsass.exe
.
Tiêm mã độc vào RAM (Kỹ thuật tàng hình/Fileless): Dưới đây là một ví dụ thực chiến từ log Sysmon
:
Source Image: C:\Users\sarah.miller\Downloads\ckjg.exe
Target Image: C:\Windows\System32\Wbem\wmic.exe
Granted Access: 0x1FFFFF
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+...|UNKNOWN(00007FF7CE73CB77)
Phân tích góc nhìn SOC:
Một file có tên ngẫu nhiên ckjg.exe tải về từ thư mục Downloads lại đi chọc vào công cụ quản lý hệ thống wmic.exe của Windows
.
Quyền truy cập là 0x1FFFFF (Full Access) – một quyền tối thượng cực kỳ đáng ngờ
.
Đáng chú ý nhất là trường CallTrace. Nó hiển thị chuỗi thư viện được gọi, nhưng ở đoạn cuối lại xuất hiện vùng nhớ UNKNOWN(00007FF7CE73CB77). Điều này cho thấy mã thực thi đang chạy ở một vùng nhớ không xác định, một dấu hiệu kinh điển của việc mã độc giải nén (unpack) shellcode trực tiếp vào RAM để né phần mềm diệt virus quét file vật lý
.
2. Event ID 11 (File Creation): Theo dấu các điểm neo Persistence
Hacker có thể chạy mã độc trên RAM, nhưng để duy trì sự hiện diện (Persistence) qua những lần khởi động lại máy, chúng buộc phải để lại một thứ gì đó trên ổ đĩa. Thay vì cấu hình Audit Object Access phức tạp để lấy Event ID 4663 của Windows, Sysmon Event ID 11 mặc định ghi lại toàn bộ các file thực thi được tạo ra
.
Dựa vào tiến trình đáng ngờ ckjg.exe ở trên, nếu ta tra cứu tiếp Event ID 11, ta sẽ bắt được ngay hành động giấu file của nó
:
ProcessId: 1460
Image: C:\Users\sarah.miller\Downloads\ckjg.exe
TargetFilename: C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url
Chỉ với một log duy nhất, Sysmon EID 11 đã vạch trần việc mã độc vừa âm thầm tạo một file khởi động tên là DeleteApp.url nhét thẳng vào thư mục Startup của người dùng để kích hoạt cùng hệ thống
.
3. Event ID 3 (Network Connection): Bắt tại trận Reverse Shell
Mã độc lấy cắp dữ liệu xong thì phải gửi ra ngoài, hoặc nó cần kết nối về máy chủ C2 (Command & Control) để nhận lệnh.
Nhật ký tường lửa mặc định của Windows (EID 5156) thường sinh ra quá nhiều "rác" (noise), nhưng Sysmon Event ID 3 lại là một tuyệt tác vì nó gắn trực tiếp kết nối mạng đó với một tiến trình cụ thể
.
Khi soi tiếp tiến trình ckjg.exe bằng EID 3, ta thu được
:
Protocol: tcp
Source IP: 10.10.57.125 (Máy nạn nhân)
Destination IP: 193.46.217.4
Destination Port: 7777
[Mẹo SOC]: Cổng 7777 thường không phải là cổng dịch vụ chuẩn. Sự kết hợp giữa một tiến trình rác trong thư mục Downloads, thực hiện Process Injection (EID 10), thả file vào Startup (EID 11) và mở cổng TCP ra IP bên ngoài (EID 3) là một bằng chứng 100% về một cuộc tấn công Reverse Shell đang diễn ra
.
4. Đối phó với Timestomping và Fileless nâng cao
4.1 Timestomping (Giả mạo thời gian)
Trong quá trình điều tra Forensics, timeline là yếu tố sống còn. Để đánh lừa các nhà phân tích, hacker sử dụng kỹ thuật Timestomping – dùng công cụ sửa đổi ngày tạo (Creation Time) của mã độc lùi về quá khứ để trông giống như một tệp hệ thống đã tồn tại từ lâu.
Ví dụ, trong một ổ đĩa FAT32 bị điều tra, ta có thể thấy một file install.txt có thời gian truy cập cuối (Accessed Time) là năm 2018, nhưng thời gian tạo (Created Time) lại là năm 2025. Đây là dấu vết thao túng thời gian rõ rệt
.
Để bắt được hành vi này ngay lập tức, ta sử dụng Sysmon Event ID 2. Nếu Windows Event ID 4670 chỉ đơn thuần ghi nhận thay đổi quyền/thuộc tính, thì Sysmon EID 2 được thiết kế đặc biệt để phát hiện và cảnh báo ngay khi có kẻ cố tình sửa đổi thời gian tạo của tệp tin
.
4.2 Giám sát Fileless qua PowerShell (Event ID 4104)
Khi nói đến mã độc không để lại file, PowerShell là công cụ bị lạm dụng nhiều nhất. Hacker sẽ truyền các chuỗi lệnh đã mã hóa Base64 thẳng vào RAM. Nếu chỉ nhìn Sysmon EID 1, bạn sẽ chỉ thấy câu lệnh powershell -encodedCommand ... vô nghĩa.
Để đối phó, SOC Analyst phải bật tính năng Script Block Logging (Event ID 4104) trong nhánh Microsoft-Windows-PowerShell/Operational. Ngay cả khi hacker mã hóa code, PowerShell bắt buộc phải tự giải mã nó trên RAM để thực thi. Lúc này, EID 4104 sẽ chộp lại và lưu trữ toàn bộ nội dung code dạng nguyên bản (clear-text)
.
Bạn cũng có thể theo dõi Event ID 4103 (Module Logging) để xem chính xác các tham số và biến số (Parameter Binding) nào đã được nạp vào, giúp truy vết tận gốc nguồn tài nguyên độc hại
.

--------------------------------------------------------------------------------
Bằng cách kết hợp Sysmon (EID 3, 10, 11) cùng các nhật ký giám sát PowerShell, bạn đã dựng lên một lưới điện an ninh dày đặc. Mã độc có thể đổi tên, giấu file, giả mạo thời gian hay chạy trên RAM, nhưng chúng không bao giờ có thể xóa bỏ hoàn toàn những chuỗi hành vi logic mà chúng tạo ra trên hệ điều hành. Chúc các bạn áp dụng hiệu quả vào hệ thống SIEM của mình để trở thành một Threat Hunter xuất sắc!