rule TTP_XOR_WriteProcessMemory_2978 {
  strings:
    $key_2978 = { 7e 0a [2] 4c 28 [2] 4a 1d [2] 64 1d [2] 5b 01 }

  condition:
    any of them
}