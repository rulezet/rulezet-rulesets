rule TTP_XOR_WriteProcessMemory_d658 {
  strings:
    $key_d658 = { 81 2a [2] b3 08 [2] b5 3d [2] 9b 3d [2] a4 21 }

  condition:
    any of them
}