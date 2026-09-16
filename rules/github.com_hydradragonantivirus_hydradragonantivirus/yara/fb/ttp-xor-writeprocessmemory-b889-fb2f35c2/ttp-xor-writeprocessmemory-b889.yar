rule TTP_XOR_WriteProcessMemory_b889 {
  strings:
    $key_b889 = { ef fb [2] dd d9 [2] db ec [2] f5 ec [2] ca f0 }

  condition:
    any of them
}