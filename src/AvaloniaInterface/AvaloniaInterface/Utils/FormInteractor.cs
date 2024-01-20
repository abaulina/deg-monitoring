using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;
using Avalonia.Threading;
using CryptographyLib;
using System;
using System.Threading.Tasks;

namespace AvaloniaInterface.Utils
{
    public class FormInteractor : IConsoleExtended
    {
        private readonly TextBlock _textBlock;
        private readonly ScrollViewer _scrollViewer;

        private readonly bool _isTextBoxSet = true;

        private const int ConsoleLimit = 300;

        public FormInteractor(TextBlock textBox, ScrollViewer scrollViewer)
        {
            _textBlock = textBox;
            _textBlock.Text = "";

            _scrollViewer = scrollViewer;
        }

        public async Task PrintError(string message)
        {
            if (!_isTextBoxSet)
                return;
            await AppendColoredText(message, Colors.Red);
        }

        public void ShowError(string message)
        {
            throw new NotImplementedException();
        }

        public async Task PrintWarning(string message)
        {
            if (!_isTextBoxSet)
                return;
            await AppendColoredText(message, Colors.Yellow);
        }

        public async Task PrintSuccess(string message)
        {
            if (!_isTextBoxSet)
                return;
            await AppendColoredText(message, Colors.Green);
        }

        public bool PrintQuestion(string message)
        {
            /*var result = MessageBox.Show(_form, message, string.Empty, MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            return result == DialogResult.Yes; */
            throw new NotImplementedException();
        }

        public void Clear()
        {
            _textBlock.Text = "";
        }

        public async Task Print(string message)
        {
            await AppendColoredText(message);
        }

        private async Task AppendColoredText(string message, Color? color = null)
        {
            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                {
                    if (!_isTextBoxSet)
                        return;

                    Run run = new Run();
                    run.Text = message + "\n";

                    if (color != null)
                    {
                        run.Foreground = new SolidColorBrush((Color)color);
                    }


                    var textBoxLength = _textBlock.Inlines.Count;
                    if (textBoxLength > ConsoleLimit)
                    {
                        _textBlock.Inlines.RemoveRange(0, textBoxLength - ConsoleLimit);
                    }


                    _textBlock.Inlines.Add(run);

                    _scrollViewer.ScrollToEnd();
                }
            }, DispatcherPriority.MaxValue);

        }

    }
}
