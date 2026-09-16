rule TTP_XOR_WriteProcessMemory_fffc {
  strings:
    $key_fffc = { a8 8e [2] 9a ac [2] 9c 99 [2] b2 99 [2] 8d 85 }

  condition:
    any of them
}