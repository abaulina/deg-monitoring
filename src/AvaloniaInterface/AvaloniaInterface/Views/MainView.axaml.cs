using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using AvaloniaInterface.Utils;
using CryptographyLib;
using CryptographyLib.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reactive.Subjects;
using System.Threading.Tasks;

namespace AvaloniaInterface.Views;

public partial class MainView : UserControl
{
    private TextBlock _logTextBox;
    private IConsoleExtended _console;
    private readonly TxProcessor _txProcessor;
    private Subject<string> _displayedMessages;
    private HashSet<string> _recievedMessages;
    private TextBlock _selectedFolderPathTB;
    private ScrollViewer _logScrollViewer;
    private string _selectedFolderPath;
    public MainView()
    {
        AvaloniaXamlLoader.Load(this);
        _logTextBox = this.FindControl<TextBlock>("LogTextBox")!;
        _selectedFolderPathTB = this.Find<TextBlock>("SelectedFolderPath")!;
        _logScrollViewer = this.Find<ScrollViewer>("LogScrollViewer")!;
        _console = new FormInteractor(_logTextBox, _logScrollViewer);
        _displayedMessages = new Subject<string>();
        _recievedMessages = new HashSet<string>();
        _txProcessor = new TxProcessor(isBenchmark: false);
        _txProcessor.MessagesChanged += MessagesChanged!;

        this.KeyUp += MainWindow_KeyUp;

        this.SizeChanged += MainWindow_Rezise;
    }

    private void MainWindow_KeyUp(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            click_GetFolderPath(null, null);
        }
    }

    private void MainWindow_Rezise(object sender, SizeChangedEventArgs e)
    {
        if (e.HeightChanged)
            _logScrollViewer.Height = e.NewSize.Height - 100;
    }

    private async void MessagesChanged(object sender, EventArgs e)
    {
        if (sender is LogMessage logMessage)
        {
            switch (logMessage.MessageType)
            {
                case LogMessageType.Error:
                    await _console.PrintError(logMessage.Message);
                    break;
                default:
                    await _console.Print(logMessage.Message);
                    break;
            }
        }
    }





    private async void click_GetFolderPath(object sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this)!;

        var folders = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Выберите папку с архивами",
            AllowMultiple = false
        });
        var selectedFolder = folders.FirstOrDefault()?.Path.LocalPath;

        if (!string.IsNullOrEmpty(selectedFolder))
        {
            _selectedFolderPathTB.Text = $"{selectedFolder}";
            _selectedFolderPath = selectedFolder;

            await Task.Run(() => startValidation());
        }
        else
        {
            _selectedFolderPathTB.Text = "Не удалось выбрать папку, попробуйте ещё раз";
        }

    }

    private void startValidation()
    {
        //_console.Clear();
        _displayedMessages = new Subject<string>();
        _txProcessor.ProcessTxFiles(_selectedFolderPath);
    }

}

