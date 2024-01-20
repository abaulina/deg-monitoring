using System.Collections.ObjectModel;

namespace AvaloniaInterface.ViewModels;

public class MainViewModel : ViewModelBase
{
    private ObservableCollection<string> _recievedMessages;

    public ObservableCollection<string> RecievedMessages
    {
        get { return _recievedMessages; }
        set { _recievedMessages = value; }
    }
    public MainViewModel()
    {
        _recievedMessages = new ObservableCollection<string>();
    }
}
