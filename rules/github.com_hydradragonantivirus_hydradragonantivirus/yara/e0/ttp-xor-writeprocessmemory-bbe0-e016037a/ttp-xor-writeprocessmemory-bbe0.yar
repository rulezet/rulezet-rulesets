rule TTP_XOR_WriteProcessMemory_bbe0 {
  strings:
    $key_bbe0 = { ec 92 [2] de b0 [2] d8 85 [2] f6 85 [2] c9 99 }

  condition:
    any of them
}