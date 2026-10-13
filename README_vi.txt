# Bộ source công cụ Luraph

Bên trong có hai cây source riêng, kèm LICENSE và runtime Luau dùng trong lượt phân tích.

## v14.7
`v14.7_experimental_source/` là source từ:
https://github.com/caomod2077/Deobfuscator-Luraph-V15
Commit: 892b48ac200e9deda6cd6fd3142bf66abed393c6

Đây là bộ hỗ trợ v14.x mang tính thử nghiệm. Với `printsample.txt`, nó lift được cấu trúc VM nhưng từ chối kết quả bootstrap; câu lệnh payload `print("hii!! luraph 14.7")` được lấy qua payload trace cô lập. Vì vậy source này không tạo ra một bản static decompile đầy đủ cho mẫu đó.

## v15.1 — source đã thử, không phải source tạo ra output trước đó
`v15_tool_attempt_source/` là source từ:
https://github.com/Aditya-lua/Deobfuscator-Luraph-V15
Commit: 01516714641ca20ebb5cc22a9cf4391e38e24735

Tool này đã được chạy thử trên mẫu v15.1, nhưng lượt chạy trả về 0 hàm được lift và dừng ở vòng lặp vô hạn; nó KHÔNG tạo ra `Deobfuscated_Source_Luraph_v15.1.lua`.

Output v15.1 trước đó đến từ một sample/output công khai có input trùng byte-for-byte với file đã tải lên. Nguồn công khai:
https://github.com/4fundsagent-source/luau.site/issues/5
Input SHA-256: 73f876c6f2bd2c610b0e8aed0581f1f85194b94c53707c635c9269dcb4991038

## Runtime
`bin/luau` và `bin/luau-ast` là Linux executables; `.exe` là Windows executables. Chúng là runtime binaries, không phải source code. Các thư mục `sample`, cache, `.git`, và artefact chạy thử đã được loại khỏi gói.
