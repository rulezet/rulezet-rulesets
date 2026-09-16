rule _Virus_Hijack_Gen_Trojan_ShellObject_dyX_ai9jxwp_1_1_Virus_Hijac_403 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash2       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash3       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"

  strings:
    $s1  = "WinLauncher external command processing thread" fullword ascii
    $s2  = "NOTE: We have detected that you are running a 64-bit version of the Windows operating system but are running the 32-bit executab" ascii
    $s3  = "NOTE: We have detected that you are running a 64-bit version of the Windows operating system but are running the 32-bit executab" ascii
    $s4  = "Error sending command line to existing instance" fullword wide
    $s5  = "If you already have a 64-bit JDK installed, define a JAVA_HOME variable in Computer > System Properties > System Settings > Envi" ascii
    $s6  = "Failed to load JVM DLL " fullword ascii
    $s7  = "If you already have a 64-bit JDK installed, define a JAVA_HOME variable in Computer > System Properties > System Settings > Envi" ascii
    $s8  = " [-l|--line line] [project_dir|--temp-project] file[:line]" fullword ascii
    $s9  = "Improperly specified VM option. To fix the problem, edit your JVM options and remove the options that are obsolete or not suppor" ascii
    $s10 = "Computer > System Properties > System Settings > Environment Variables." fullword ascii
    $s11 = " -h | -? | --help" fullword ascii
    $s12 = "le. This can prevent you from finding a 64-bit installation of Java. Consider running the 64-bit version instead, if this is the" ascii
    $s13 = "If you already have a JDK installed, define a JAVA_HOME variable in" fullword ascii
    $s14 = "ted by the current version of the JVM." fullword ascii
    $s15 = "Error invoking main method" fullword ascii
    $s16 = "The environment variable %s (with the value of %s) does not point to a valid JVM installation." fullword ascii
    $s17 = "Failed to create JVM. " fullword ascii
    $s18 = "If you already have a 64-bit JDK installed, define a JAVA_HOME variable in " fullword ascii
    $s19 = " problem you're encountering." fullword ascii
    $s20 = " diff <left> <right>" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}