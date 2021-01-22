<#
.SYNOPSIS
    Used to export information to a CSV file to represent logging information.
.DESCRIPTION
    Original basis \ inspiration for this script is cited in ".NOTES.Inspired By:" below.
    Main portions of the script that were kept:
        Use of mutexes to allow for the log file to be waited for.
        Interpretation of $Error[0] and breaking it into a readable predictable string value.
        Testing of log path to create a default log based on run path.

    This function will output information to a Csv file along with allowing a choice of severities.

    This function will by default create a log file in the parent folder of the calling scope of the script.
            $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')+ "\LoggyMcLogFace.csv"

    However you can of course easily specify a location with `-LogFile`.

    Note that logs are appended to, so there is no danger of overwriting an existing LoggyMcLogFace.csv file.

        Example information level output to a specific logfile:
        Information Example:
            Write-LogEntry -Info 'This is an informational log event.' -LogFile 'C:\Temp\SuperFancyLogfile.csv'        
        Example output:
            Within 'C:\Temp\SuperFancyLogfile.csv' you would find:

            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Info","6","This is an informational log event."

    Syslog severity levels are used to mostly specify the log type:
        Syslog Severity levels https://en.wikipedia.org/wiki/Syslog#Severity_level
    Severity level
    The list of severities is also defined by the standard:[2]:10

    Value	Severity        Keyword     Deprecated keywords     Description                             Condition
    0       Emergency       emerg       panic[7]                System is unusable                      A panic condition.[8]
    1       Alert           alert                               Action must be taken immediately        A condition that should be corrected immediately, such as a corrupted system database.[8]
    2       Critical        crit                                Critical conditions                     Hard device errors.[8]
    3       Error           err	        error[7]                Error conditions
    4       Warning         warning     warn[7]                 Warning conditions
    5       Notice          notice                              Normal but significant conditions       Conditions that are not error conditions, but that may require special handling.[8]
    6       Informational   info                                Informational messages
    7       Debug           debug                               Debug-level messages                    Messages that contain information normally of use only when debugging a program.[8]

    However, we also have one, also a value level of 3 called "ErrorRecord" - this is a breakout of the returned Error object into a predicable string containing:
        1-Exception Message, 2-FullyQualifiedErrorId,3-ScriptName,4-ScriptLineNumber,5-OffsetInLine

    By default (and if not specified), the log type is 'Info'.
 
    Examples of uses
        Information Example:
            Write-LogEntry -Info 'This is an informational log event.'
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Info","6","This is an informational log event."

        Debug Example:
            Write-LogEntry -Debug 'This is an debug log event.'
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Debug","7","This is an debug log event."

    Error type log events can be used several different ways.

        Error Example 01:
            You can simply send a string to the error categorized log event output.
        Example use:
            Write-LogEntry -Error 'This is an error log event.'
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Error","3","This is an error log event."

        Error Example 02:
            You can send the basic captured error message string out to the categorized log event output message.
        Example use:
            try { 
                fail-atsomething
            } catch { 
                Write-LogEntry -Error '$Error[0]'
            }
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Error","3","The term 'fail-atsomething' is not recognized...verify that the path is correct and try again."

        Error Example 03:
            Using 'ErrorRecord' you can break out the captured $Error[0] event to show error information you would normally expect in console.
            This includes the exception type, and line + character information.
        Example use:
            try { 
                fail-atsomething
            } catch { 
                Write-LogEntry -Error '$Error[0]'
            }
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","ErrorRecord","3","The term 'fail-atsomething' is not recognized...verify that the path is correct and try again. (CommandNotFoundException: :1 char:7)"
        
    Flaws:
        I'd like to put a better definition on how long the wait will be for when awaiting file access.

    Needs:
        Dynamic creation of different categories of severity.
        Being able to specify separation value of Csv.
        Would be nice to also have this be able to send directly to a SQL DB.

    -v 0.9  (2019 07 19) :  Initial changes.  
    -v 1.0  (2019 07 24) :  Documentation / Examples / Description
    -v 2.0  (2021 01 22) :  Syslog levels of severity

.EXAMPLE
        Information Specific Logfile Example:
            Write-LogEntry -Info 'This is an informational log event.' -LogFile 'C:\Temp\SuperFancyLogfile.csv'        
        Example output:
            Within 'C:\Temp\SuperFancyLogfile.csv' you would find:

            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Info","6","This is an informational log event."

.EXAMPLE
        Information Example:
            Write-LogEntry -Info 'This is an informational log event.'
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Info","6","This is an informational log event."
.EXAMPLE
        Debug Example:
            Write-LogEntry -Debug 'This is an debug log event.'
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Debug","7","This is an debug log event."
.EXAMPLE
        Error Example 01:
            You can simply send a string to the error categorized log event output.
        Example use:
            Write-LogEntry -Error 'This is an error log event.'
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Error","3","This is an error log event."
.EXAMPLE
        Error Example 02:
            You can send the basic captured error message string out to the categorized log event output message.
        Example use:
            try { 
                fail-atsomething
            } catch { 
                Write-LogEntry -Error '$Error[0]'
            }
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","Error","3","The term 'fail-atsomething' is not recognized...verify that the path is correct and try again."
.EXAMPLE
        Error Example 03:
            Using 'EventRecord' you can break out the captured $Error[0] event to show error information you would normally expect in console.
            This includes the exception type, and line + character information.
        Example use:
            try { 
                fail-atsomething
            } catch { 
                Write-LogEntry -Error '$Error[0]'
            }
        Example output:
            "Time","Severity","SeverityNumber","Message"
            "20190718T162503","ErrorRecord","3","The term 'fail-atsomething' is not recognized...verify that the path is correct and try again. (CommandNotFoundException: :1 char:7)"
.INPUTS
    System.String
    System.Management.Automation.ErrorRecord
.NOTES
    File Name       :   Write-LogEntry.ps1
    Author          :   Jonathan Weinberg, email@jonathanweinberg.me
    Prerequisite    :   PowerShell V5
    Date            :   2019/07/24
    Version         :   2.0
    Original Basis  :   Josh Rickard / 11/24/2016 / https://github.com/MSAdministrator/WriteLogEntry/blob/master/Public/Write-LogEntry.ps1
#>

#region LoggingFunction
function Write-LogEntry {
    [CmdletBinding(DefaultParameterSetName = 'Info',
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        HelpUri = 'https://www.microsoft.com',
        ConfirmImpact = 'Medium')]
    [OutputType()]
    Param
    (
        # Debug type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Debug')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Debugging,

        # Information type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Info')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Info,

        # Notice type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Notice')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Notice,

        # Warning type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Warning')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Warning,

        # Error type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Error')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Error,

        # The error record containing an exception to log
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'ErrorRecord')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        # Critical type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Critical')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Critical,

        # Alert type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Alert')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Alert,

        # Emergency type of log entry
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Emergency')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [System.String]$Emergency,

        # Logfile location
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1)]
        [System.String]$LogFile = "$($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\'))" + "\LoggyMcLogFace.csv"
    )

    if (!(Test-Path -Path $LogFile)) {
        try {
            New-Item -Path $LogFile -ItemType File -Force | Out-Null
        }
        catch {
            Write-Error -Message 'Error creating log file'
            break
        }
    }
    $mutex = New-Object -TypeName 'Threading.Mutex' -ArgumentList $false, 'MyInterprocMutex'
    switch ($PSBoundParameters.Keys) {
        'Debugging' {
            Write-Debug -Message "$Debugging"
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Debugging'
                SeverityNumber = '7'
                Message        = $Debugging
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Info' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Info'
                SeverityNumber = '6'
                Message        = $Info
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Notice' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Notice'
                SeverityNumber = '5'
                Message        = $Notice
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Warning' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Warning'
                SeverityNumber = '4'
                Message        = $Warning
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Error' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Error'
                SeverityNumber = '3'
                Message        = $Error.ToString()
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'ErrorRecord' {
            $mutex.waitone() | Out-Null
            $Message = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
            $ErrorRecord.FullyQualifiedErrorId,
            $ErrorRecord.InvocationInfo.ScriptName,
            $ErrorRecord.InvocationInfo.ScriptLineNumber,
            $ErrorRecord.InvocationInfo.OffsetInLine
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'ErrorRecord'
                SeverityNumber = '3'
                Message        = $Message
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Critical' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Critical'
                SeverityNumber = '2'
                Message        = $Critical
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Alert' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Alert'
                SeverityNumber = '1'
                Message        = $Error.ToString()
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
        'Emergency' {
            $mutex.waitone() | Out-Null
            [PSCustomObject]@{
                Time           = $((Get-Date).ToString('yyyyMMddTHHmmss'))
                Severity       = 'Emergency'
                SeverityNumber = '0'
                Message        = $Emergency
            } | Export-Csv -Path $LogFile -Append -NoTypeInformation
            $mutex.ReleaseMutex() | Out-Null
        }
    }
}
#endregion LoggingFunction

<#
MIT License

Copyright (c) 2019 Jonathan Weinberg

Copyright (c) 2017 Josh Rickard

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>