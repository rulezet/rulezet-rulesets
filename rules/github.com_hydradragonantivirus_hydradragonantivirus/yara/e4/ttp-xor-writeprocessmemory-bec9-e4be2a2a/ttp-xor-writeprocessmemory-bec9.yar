rule TTP_XOR_WriteProcessMemory_bec9 {
  strings:
    $key_bec9 = { e9 bb [2] db 99 [2] dd ac [2] f3 ac [2] cc b0 }

  condition:
    any of them
}