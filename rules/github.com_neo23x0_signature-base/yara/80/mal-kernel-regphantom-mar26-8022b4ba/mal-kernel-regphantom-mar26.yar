rule MAL_Kernel_RegPhantom_Mar26 {
   meta:
      description = "Detects RegPhantom, a kernel-mode rootkit that allow attacker to inject arbitrary code from unprivileged user-mode into kernel-mode and execute it."
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-03-19"
      reference = "Internal Research"
      hash = "006e08f1b8cad821f7849c282dc11d317e76ce66a5bcd84053dd5e7752e0606f"
      score = 80
      id = "aa8963b5-3053-52a4-a84f-2fc02d03275e"
   strings:
      $s1 = "CmRegisterCallback" fullword
      $s2 = "PsSetCreateThreadNotifyRoutine" fullword

      $o1 = {
                  48 8b 09              0f b6 14 08           4c 31 c2              88 14 08           }
      $o2 = {
                  c6 01 01              48 83 38 77           0f 94 c0              24 01              }
   condition:
      uint16(0) == 0x5a4d
      and all of them
}