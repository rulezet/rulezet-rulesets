rule TTP_XOR_WriteProcessMemory_dbcf {
  strings:
    $key_dbcf = { 8c bd [2] be 9f [2] b8 aa [2] 96 aa [2] a9 b6 }

  condition:
    any of them
}