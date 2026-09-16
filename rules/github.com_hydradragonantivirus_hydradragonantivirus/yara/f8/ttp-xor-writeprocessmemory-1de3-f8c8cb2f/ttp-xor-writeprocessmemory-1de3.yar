rule TTP_XOR_WriteProcessMemory_1de3 {
  strings:
    $key_1de3 = { 4a 91 [2] 78 b3 [2] 7e 86 [2] 50 86 [2] 6f 9a }

  condition:
    any of them
}