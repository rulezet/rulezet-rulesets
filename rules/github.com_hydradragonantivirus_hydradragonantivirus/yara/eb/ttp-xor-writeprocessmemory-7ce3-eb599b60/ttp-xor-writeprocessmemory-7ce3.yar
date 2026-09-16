rule TTP_XOR_WriteProcessMemory_7ce3 {
  strings:
    $key_7ce3 = { 2b 91 [2] 19 b3 [2] 1f 86 [2] 31 86 [2] 0e 9a }

  condition:
    any of them
}