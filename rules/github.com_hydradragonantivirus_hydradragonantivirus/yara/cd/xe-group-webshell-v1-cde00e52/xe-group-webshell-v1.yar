rule XE_Group_webshell_V1 {
  meta:
    author      = "Intezer Labs"
    description = "Detect WebShell from XE Group attacks in 2020"
    date        = "13-12-2024"
    version     = "1.0"
    hash        = "680b7e8ec8204975c5026bcbaf70f7e9620eacdd7bf72e5476d17266b4a7d316"
    reference   = "https://intezer.com/blog/research/xe-group-exploiting-zero-days/"

  strings:
    $w_1 = "<%@ Page Language=\"C#"
    $w_2 = "EnableViewState=\"true\"%>"
    $w_3 = "<script runat=\"server\">"

    $pageload_function = "protected void Page_load(" ascii

        $s1 = "sqlCommandQuery" ascii
    $s2 = "ismatchagent" ascii
    $s3 = "IsServerConnected" ascii
    $s4 = "DATABASE=master;connect timeout=10;" ascii
    $s5 = "WGVUaGFuaHxYZUdyb3Vwcw==" ascii
    $s6 = "\"Success Connection\";" ascii
    $s7 = "\"You sure scan all connect on this server?\"" ascii
    $s8 = "Please enter connect string. Server address of connect string must valid IP!" ascii

        $q1 = "RECONFIGURE;EXEC sp_configure 'show advanced options', 1;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;" ascii
    $q2 = "SELECT o.NAME, i.rowcnt FROM sysindexes AS i INNER JOIN sysobjects AS o ON i.id = o.id WHERE i.indid < 2  AND i.rowcnt > 0 AND OBJECTPROPERTY(o.id, 'IsMSShipped') = 0 ORDER BY i.rowcnt DESC" ascii
    $q3 = "SELECT name,crdate,filename FROM master.dbo.sysdatabases" ascii
    $q4 = "SELECT TOP 100 * FROM [XXXXX] ORDER BY 1 DESC" ascii

  condition:
    2 of ($w_*)      and
    $pageload_function
    and
    (
      1 of ($s*)
      or
      1 of ($q*)
    )
}