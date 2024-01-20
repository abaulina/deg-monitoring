namespace CryptographyLib;

public interface IConsoleExtended
{
    Task PrintWarning(string message);

    Task PrintError(string message);

    void ShowError(string message);

    Task PrintSuccess(string message);

    bool PrintQuestion(string message);

    void Clear();

    Task Print(string message);
}