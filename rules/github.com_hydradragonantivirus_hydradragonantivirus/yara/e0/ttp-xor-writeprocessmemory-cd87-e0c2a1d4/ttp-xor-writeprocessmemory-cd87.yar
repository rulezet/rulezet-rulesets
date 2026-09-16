rule TTP_XOR_WriteProcessMemory_cd87 {
  strings:
    $key_cd87 = { 9a f5 [2] a8 d7 [2] ae e2 [2] 80 e2 [2] bf fe }

  condition:
    any of them
}