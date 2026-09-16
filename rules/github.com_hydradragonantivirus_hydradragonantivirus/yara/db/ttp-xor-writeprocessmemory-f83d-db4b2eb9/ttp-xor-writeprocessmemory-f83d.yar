rule TTP_XOR_WriteProcessMemory_f83d {
  strings:
    $key_f83d = { af 4f [2] 9d 6d [2] 9b 58 [2] b5 58 [2] 8a 44 }

  condition:
    any of them
}