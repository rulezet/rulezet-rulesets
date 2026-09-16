rule TTP_XOR_WriteProcessMemory_2386 {
  strings:
    $key_2386 = { 74 f4 [2] 46 d6 [2] 40 e3 [2] 6e e3 [2] 51 ff }

  condition:
    any of them
}