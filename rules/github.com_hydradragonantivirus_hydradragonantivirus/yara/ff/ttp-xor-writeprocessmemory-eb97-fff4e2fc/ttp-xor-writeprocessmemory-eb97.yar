rule TTP_XOR_WriteProcessMemory_eb97 {
  strings:
    $key_eb97 = { bc e5 [2] 8e c7 [2] 88 f2 [2] a6 f2 [2] 99 ee }

  condition:
    any of them
}