using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace AvaloniaInterface.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    public void InitializeComponent()
    {
        this.Height = 600;
        this.Width = 800;
        AvaloniaXamlLoader.Load(this);
    }
}
