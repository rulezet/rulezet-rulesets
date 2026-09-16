rule TTP_XOR_WriteProcessMemory_ceb8 {
  strings:
    $key_ceb8 = { 99 ca [2] ab e8 [2] ad dd [2] 83 dd [2] bc c1 }

  condition:
    any of them
}