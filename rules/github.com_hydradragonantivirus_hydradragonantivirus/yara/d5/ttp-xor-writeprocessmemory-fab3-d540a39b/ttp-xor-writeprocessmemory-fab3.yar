rule TTP_XOR_WriteProcessMemory_fab3 {
  strings:
    $key_fab3 = { ad c1 [2] 9f e3 [2] 99 d6 [2] b7 d6 [2] 88 ca }

  condition:
    any of them
}