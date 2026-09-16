rule TTP_XOR_WriteProcessMemory_ff0d {
  strings:
    $key_ff0d = { a8 7f [2] 9a 5d [2] 9c 68 [2] b2 68 [2] 8d 74 }

  condition:
    any of them
}