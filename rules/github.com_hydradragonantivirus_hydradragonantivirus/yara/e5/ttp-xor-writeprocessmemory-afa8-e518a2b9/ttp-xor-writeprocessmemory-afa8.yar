rule TTP_XOR_WriteProcessMemory_afa8 {
  strings:
    $key_afa8 = { f8 da [2] ca f8 [2] cc cd [2] e2 cd [2] dd d1 }

  condition:
    any of them
}