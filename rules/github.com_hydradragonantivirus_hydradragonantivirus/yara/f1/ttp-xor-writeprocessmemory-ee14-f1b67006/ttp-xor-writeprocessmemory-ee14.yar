rule TTP_XOR_WriteProcessMemory_ee14 {
  strings:
    $key_ee14 = { b9 66 [2] 8b 44 [2] 8d 71 [2] a3 71 [2] 9c 6d }

  condition:
    any of them
}