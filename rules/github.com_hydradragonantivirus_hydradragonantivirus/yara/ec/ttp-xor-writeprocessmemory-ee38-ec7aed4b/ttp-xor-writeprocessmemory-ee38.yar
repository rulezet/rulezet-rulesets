rule TTP_XOR_WriteProcessMemory_ee38 {
  strings:
    $key_ee38 = { b9 4a [2] 8b 68 [2] 8d 5d [2] a3 5d [2] 9c 41 }

  condition:
    any of them
}