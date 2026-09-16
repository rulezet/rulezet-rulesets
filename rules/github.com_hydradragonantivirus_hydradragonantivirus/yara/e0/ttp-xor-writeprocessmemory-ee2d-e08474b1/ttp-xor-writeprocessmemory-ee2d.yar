rule TTP_XOR_WriteProcessMemory_ee2d {
  strings:
    $key_ee2d = { b9 5f [2] 8b 7d [2] 8d 48 [2] a3 48 [2] 9c 54 }

  condition:
    any of them
}