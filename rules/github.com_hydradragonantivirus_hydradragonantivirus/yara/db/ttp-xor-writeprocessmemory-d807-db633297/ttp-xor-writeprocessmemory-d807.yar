rule TTP_XOR_WriteProcessMemory_d807 {
  strings:
    $key_d807 = { 8f 75 [2] bd 57 [2] bb 62 [2] 95 62 [2] aa 7e }

  condition:
    any of them
}