## Using the wonderful ImportExcel module - https://github.com/dfinke/ImportExcel

$toWork = Import-Csv -Path "C:\temp\example.csv"
$toWork | Export-Excel -Path "C:\temp\example.xlsx" -WorksheetName "DataSheet" -FreezeTopRow -BoldTopRow -TableName "Data" -AutoSize -NoNumberConversion *
$wbk = Open-ExcelPackage -Path "C:\temp\example.xlsx"

$Columns = "1","2","16","18","26","28","40","42","44","52","53","54","55","56","57","58","59","60"

foreach ($Column in $Columns) {
    if ($Column -ne '43') {
        Set-ExcelColumn -ExcelPackage $wbk -WorksheetName "DataSheet" -Column $Column -Hide
    }
    if ($Column -eq '43') {
        Set-ExcelColumn -ExcelPackage $wbk -WorksheetName "DataSheet" -Column "43" -NumberFormat 'Text'
    }
}

Export-Excel -ExcelPackage $wbk -NoNumberConversion *