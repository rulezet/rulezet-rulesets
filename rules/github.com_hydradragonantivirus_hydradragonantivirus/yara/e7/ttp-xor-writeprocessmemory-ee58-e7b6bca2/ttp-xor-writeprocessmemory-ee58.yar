rule TTP_XOR_WriteProcessMemory_ee58 {
  strings:
    $key_ee58 = { b9 2a [2] 8b 08 [2] 8d 3d [2] a3 3d [2] 9c 21 }

  condition:
    any of them
}