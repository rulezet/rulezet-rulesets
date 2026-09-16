rule TTP_XOR_WriteProcessMemory_fcec {
  strings:
    $key_fcec = { ab 9e [2] 99 bc [2] 9f 89 [2] b1 89 [2] 8e 95 }

  condition:
    any of them
}