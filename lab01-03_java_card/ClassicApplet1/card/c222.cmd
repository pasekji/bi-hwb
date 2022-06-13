@rem compile applet with JcDK 2.2.2
set PACKAGE=classicapplet1
set APPLET=ClassicApplet1
c:\PROGRA~1\Java\jdk1.8.0_111\bin\javac.exe -g -target 1.1 -source 1.2 -cp %JC_HOME%\lib\api.jar -d . ../src/%PACKAGE%/*.java
c:\java_card\java_card_kit-2_2_2\bin\converter.bat -exportpath %JC_HOME%\api_export_files -applet 0x01:0x02:0x03:0x04:0x5:0x6:0x8:0x9 %PACKAGE%.%APPLET% %PACKAGE% 0x01:0x02:0x03:0x04:0x5:0x6:0x8 1.0
