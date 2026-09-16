rule TTP_XOR_WriteProcessMemory_ee0c {
  strings:
    $key_ee0c = { b9 7e [2] 8b 5c [2] 8d 69 [2] a3 69 [2] 9c 75 }

  condition:
    any of them
}