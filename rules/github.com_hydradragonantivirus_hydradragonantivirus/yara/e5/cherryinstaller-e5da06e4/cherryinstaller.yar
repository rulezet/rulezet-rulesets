rule cherryInstaller
{
    strings:
        $string1 = "(inject base: %08x)"
        $string2 = "injected ok"
        $string3 = "inject failed"
        $string4 = "-i name.dll - install path dll"
        $string5 = "-s name.dll procname|PID - inject dll into processes or PID"
        $fileinfect1 = "\\ServicePackFiles\\i386\\user32.dll"
        $fileinfect2 = "\\dllcache\\user32.dll"
        $fileinfect3 = "\\user32.tmp"

    condition:
        all of ($string*) or all of ($fileinfect*)
}