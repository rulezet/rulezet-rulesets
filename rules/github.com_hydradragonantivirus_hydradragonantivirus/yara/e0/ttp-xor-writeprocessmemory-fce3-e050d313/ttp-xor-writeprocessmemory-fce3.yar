rule TTP_XOR_WriteProcessMemory_fce3 {
  strings:
    $key_fce3 = { ab 91 [2] 99 b3 [2] 9f 86 [2] b1 86 [2] 8e 9a }

  condition:
    any of them
}