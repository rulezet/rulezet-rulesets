rule TTP_XOR_WriteProcessMemory_afa6 {
  strings:
    $key_afa6 = { f8 d4 [2] ca f6 [2] cc c3 [2] e2 c3 [2] dd df }

  condition:
    any of them
}