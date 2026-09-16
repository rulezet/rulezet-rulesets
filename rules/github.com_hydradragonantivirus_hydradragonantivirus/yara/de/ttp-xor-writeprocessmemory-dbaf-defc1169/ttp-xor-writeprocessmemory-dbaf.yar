rule TTP_XOR_WriteProcessMemory_dbaf {
  strings:
    $key_dbaf = { 8c dd [2] be ff [2] b8 ca [2] 96 ca [2] a9 d6 }

  condition:
    any of them
}