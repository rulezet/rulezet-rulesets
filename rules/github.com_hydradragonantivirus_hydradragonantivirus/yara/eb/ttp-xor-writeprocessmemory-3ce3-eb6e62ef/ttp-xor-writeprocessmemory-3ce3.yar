rule TTP_XOR_WriteProcessMemory_3ce3 {
  strings:
    $key_3ce3 = { 6b 91 [2] 59 b3 [2] 5f 86 [2] 71 86 [2] 4e 9a }

  condition:
    any of them
}