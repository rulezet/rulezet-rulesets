rule TTP_XOR_WriteProcessMemory_dc33 {
  strings:
    $key_dc33 = { 8b 41 [2] b9 63 [2] bf 56 [2] 91 56 [2] ae 4a }

  condition:
    any of them
}