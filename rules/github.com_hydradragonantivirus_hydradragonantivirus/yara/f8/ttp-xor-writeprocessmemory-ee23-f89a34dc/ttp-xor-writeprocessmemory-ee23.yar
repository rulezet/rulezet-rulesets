rule TTP_XOR_WriteProcessMemory_ee23 {
  strings:
    $key_ee23 = { b9 51 [2] 8b 73 [2] 8d 46 [2] a3 46 [2] 9c 5a }

  condition:
    any of them
}