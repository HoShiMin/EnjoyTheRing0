# EnjoyTheRing0 Project
Шаблон драйвера и обёртки над функциями ядра Windows для быстрой и удобной разработки в Ring0.  
Предоставляет функционал для работы с:
  
Для сборки требуются [Visual Studio Community](https://www.visualstudio.com/post-download-vs?sku=community&clcid=0x419) 
и установленный [Windows Driver Kit](https://msdn.microsoft.com/en-us/windows/hardware/gg454513.aspx).  
Для установки и запуска: [DriversAPI Utility](https://github.com/HoShiMin/DriversAPI/releases).  
Для просмотра отладочного вывода: [DebugView](https://technet.microsoft.com/ru-ru/sysinternals/bb896647.aspx).  
Для проверки работоспособности и отладки: [VMware Player](http://www.vmware.com/products/player/playerpro-evaluation.html)  
  
Обёртка для Delphi: [Здесь](https://gist.github.com/HoShiMin/6a333d1c8a24f183073e)  
Последний релиз (подписанные бинарники x86/x64): [Здесь](https://github.com/HoShiMin/EnjoyTheRing0/releases)  
  
Отключение проверки цифровой подписи и перевод в Windows в тестовый режим:  

    - Отключение проверки цифровой подписи (разрешить устанавливать неподписанные драйвера):
    bcdedit.exe /set loadoptions DISABLE_INTEGRITY_CHECKS
    bcdedit.exe /set TESTSIGNING ON

    - Включение проверки цифровой подписи (запретить устанавливать неподписанные драйвера):
    bcdedit.exe /set loadoptions ENABLE_INTEGRITY_CHECKS
    bcdedit.exe /set TESTSIGNING OFF

    - Включение поддержки ядерной отладки (kernel-debugging) для WinDbg и Kernel Debugger из WDK:
    bcdedit.exe /debug on   -  включить
    bcdedit.exe /debug off  -  выключить
