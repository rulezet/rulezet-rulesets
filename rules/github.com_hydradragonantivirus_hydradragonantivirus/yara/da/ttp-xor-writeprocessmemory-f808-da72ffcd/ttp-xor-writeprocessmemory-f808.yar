rule TTP_XOR_WriteProcessMemory_f808 {
  strings:
    $key_f808 = { af 7a [2] 9d 58 [2] 9b 6d [2] b5 6d [2] 8a 71 }

  condition:
    any of them
}