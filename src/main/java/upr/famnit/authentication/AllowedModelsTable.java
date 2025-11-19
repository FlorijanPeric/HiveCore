package upr.famnit.authentication;

import upr.famnit.components.NodeData;
import upr.famnit.components.WorkerVersion;
import upr.famnit.managers.connections.Worker;

import java.util.ArrayList;
import java.util.List;

public class AllowedModelsTable {
    private Key key;
    private ArrayList<String>tagsAllowed;

    public void SetKey(Key kateri){
        this.key=kateri;
    }
    public Key getKey(Key kateri){
        return key;
    }
    public void getArr(){

    }
}
