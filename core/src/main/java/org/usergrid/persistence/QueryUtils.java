package org.usergrid.persistence;

import org.usergrid.utils.ListUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.substringAfter;
import static org.usergrid.utils.StringUtils.stringOrSubstringBeforeFirst;

/**
 * Utilities to deal with query extraction and generation
 *
 * @author zznate
 */
public class QueryUtils {

    public static final String PARAM_QL = "ql";
    public static final String PARAM_Q = "q";
    public static final String PARAM_QUERY = "query";

    public static String queryStrFrom(Map<String,List<String>> params) {
        if ( params.containsKey(PARAM_QL)) {
            return ListUtils.first(params.get(PARAM_QL));
        } else if ( params.containsKey(PARAM_Q)) {
            return ListUtils.first(params.get(PARAM_Q));
        } else if ( params.containsKey(PARAM_QUERY)) {
            return ListUtils.first(params.get(PARAM_QUERY));
        }
        return null;
    }

    public static Object select(Object obj, String path) {
        return select(obj, path, false);
    }

    public static Object select(Object obj, String path, boolean buildResultTree) {

        if (obj == null) {
            return null;
        }

        if (org.apache.commons.lang.StringUtils.isBlank(path)) {
            return obj;
        }

        String segment = stringOrSubstringBeforeFirst(path, '.');
        String remaining = substringAfter(path, ".");

        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            Object child = map.get(segment);
            Object result = select(child, remaining, buildResultTree);
            if (result != null) {
                if (buildResultTree) {
                    Map<Object, Object> results = new LinkedHashMap<Object, Object>();
                    results.put(segment, result);
                    return results;
                } else {
                    return result;
                }
            }
            return null;
        }
        if (obj instanceof List) {
            List<Object> results = new ArrayList<Object>();
            List<?> list = (List<?>) obj;
            for (Object i : list) {
                Object result = select(i, path, buildResultTree);
                if (result != null) {
                    results.add(result);
                }
            }
            if (!results.isEmpty()) {
                return results;
            }
            return null;
        }

if (obj instanceof Entity) {
Object child = ((Entity)obj).getProperty(segment);
Object result = select(child, remaining, buildResultTree);
if (result != null) {
if (buildResultTree) {
Map<Object, Object> results = new LinkedHashMap<Object, Object>();
results.put(segment, result);
return results;
} else {
return result;
}
}
else {
return result;
}
}

        return obj;
    }
}
