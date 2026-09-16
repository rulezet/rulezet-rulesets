rule TTP_XOR_WriteProcessMemory_ffed {
  strings:
    $key_ffed = { a8 9f [2] 9a bd [2] 9c 88 [2] b2 88 [2] 8d 94 }

  condition:
    any of them
}