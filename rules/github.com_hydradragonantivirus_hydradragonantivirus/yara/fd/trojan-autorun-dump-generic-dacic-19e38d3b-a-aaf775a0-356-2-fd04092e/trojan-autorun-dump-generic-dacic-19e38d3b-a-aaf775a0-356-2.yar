rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_356_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_356_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d660b816d3e2c96db56d5d2e6743b8e649c63dda5e46327b5dbffdceab1d499"

  strings:
    $s1  = "Error - Reader - BD" fullword wide
    $s2  = "Error - Nuevo - RolPermisoCompuestoDAL" fullword wide
    $s3  = "Error - Eliminar Permiso - RolPermisoCompuestoDAL" fullword wide
    $s4  = "Error - Eliminar Rol - RolPermisoCompuestoDAL" fullword wide
    $s5  = "Error - Eliminar Permiso de Rol - RolPermisoCompuestoDAL" fullword wide
    $s6  = "Error en DataSet - BD" fullword wide
    $s7  = "Error - NonQuery - BD" fullword wide
    $s8  = "Error - DataSet - IdiomaDAL" fullword wide
    $s9  = "Error - Nuevo - IdiomaDAL" fullword wide
    $s10 = "Error - Eliminacion - IdiomaDAL" fullword wide
    $s11 = "Error - Listar - IdiomaDAL" fullword wide
    $s12 = "Error - DataSet - AerolineaDAL" fullword wide
    $s13 = "Error - Nuevo - AerolineaDAL" fullword wide
    $s14 = "Error - Eliminacion - AerolineaDAL" fullword wide
    $s15 = "Error - Listar - AerolineaDAL" fullword wide
    $s16 = "Error - FiltrarVuelos - AerolineaDAL" fullword wide
    $s17 = "Error - DataSet - AsientoDAL" fullword wide
    $s18 = "Error - Nuevo - AsientoDAL" fullword wide
    $s19 = "Error - Eliminacion - AsientoDAL" fullword wide
    $s20 = "Error - Eliminar por Vuelo - AsientoDAL" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}