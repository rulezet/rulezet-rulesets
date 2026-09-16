rule TTP_XOR_WriteProcessMemory_ff28 {
  strings:
    $key_ff28 = { a8 5a [2] 9a 78 [2] 9c 4d [2] b2 4d [2] 8d 51 }

  condition:
    any of them
}