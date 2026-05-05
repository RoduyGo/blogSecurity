---
title: "5 Lệnh Linux Cơ Bản Dành Cho Dân Mạng"
description: "Bài viết này hướng dẫn 5 lệnh Linux cơ bản nhất, hiển thị kèm Table of Contents siêu xịn."
date: 2026-05-05T22:51:07+07:00
image: 
math: false
license: 
comments: true
draft: false
categories:
    - Linux
    - Cybersecurity
tags:
    - command
    - basic
build:
    list: always
---

Mới bước chân vào thế giới Cybersecurity, làm quen với dòng lệnh Linux là kỹ năng sinh tồn đầu tiên. Dưới đây là 5 lệnh cơ bản nhất bạn cần nằm lòng!

## 1. Lệnh `ls` - Liệt kê file
Lệnh `ls` (list) dùng để hiển thị các tệp và thư mục.

**Ví dụ:**
```bash
ls -la
```
*Tham số `-la` giúp hiển thị tất cả file ẩn và chi tiết phân quyền.*

## 2. Lệnh `cd` - Chuyển thư mục
Lệnh `cd` (change directory) giúp bạn nhảy từ thư mục này sang thư mục khác.

**Ví dụ:**
```bash
cd /var/www/html
```

## 3. Lệnh `mkdir` - Tạo thư mục mới
Lệnh `mkdir` (make directory) sinh ra để giúp bạn tạo thư mục.

**Ví dụ:**
```bash
mkdir hacker_tools
```

## 4. Lệnh `cat` - Đọc nhanh nội dung file
Khi bạn cần xem nhanh file text (chẳng hạn như file cấu hình hay file log) mà không cần mở Editor.

**Ví dụ:**
```bash
cat /etc/passwd
```

## 5. Lệnh `grep` - Tìm kiếm thần tốc
Lệnh `grep` giúp bạn quét qua các file để tìm một chuỗi ký tự cụ thể. Rất tuyệt vời để phân tích log.

**Ví dụ tìm user root:**
```bash
grep "root" /etc/passwd
```

---
> **Lưu ý về Table of Contents (TOC):** 
> Thanh mục lục (TOC) ở Sidebar bên phải tự động xuất hiện nhờ vào các thẻ tiêu đề (Heading) như `## 1. Lệnh ls` mà chúng ta viết ở trên. Bạn không cần làm gì thêm, Theme Stack sẽ tự động thu thập các thẻ tiêu đề có dấu `#` này và vẽ ra mục lục rất đẹp cho bạn!