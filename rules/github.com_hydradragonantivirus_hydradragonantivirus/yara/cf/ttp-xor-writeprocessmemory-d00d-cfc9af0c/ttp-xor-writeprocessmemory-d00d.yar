rule TTP_XOR_WriteProcessMemory_d00d {
  strings:
    $key_d00d = { 87 7f [2] b5 5d [2] b3 68 [2] 9d 68 [2] a2 74 }

  condition:
    any of them
}