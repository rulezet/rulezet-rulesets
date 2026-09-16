rule TTP_XOR_WriteProcessMemory_fde8 {
  strings:
    $key_fde8 = { aa 9a [2] 98 b8 [2] 9e 8d [2] b0 8d [2] 8f 91 }

  condition:
    any of them
}