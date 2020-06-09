package com.example.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/tasks")
public class TaskController {

    @GetMapping
    public String listTasks(){
        return "任务列表";
    }

    @PostMapping
    public String newTasks(){
        return "创建了一个新的任务";
    }

    @PutMapping("/{taskId}")
    public String updateTasks(@PathVariable("taskId")Integer id){
        return "更新了一下id为:"+id+"的任务";
    }

    //@PreAuthorize("hasRole('ADMIN')")//此时需要用户角色以ROLE_开头
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")//角色全称
    //@PreAuthorize("hasPermission('/task/**', 'App\\Api\\Controllers\\UserController.index')")
    @DeleteMapping("/{taskId}")
    public String deleteTasks(@PathVariable("taskId")Integer id){
        return "删除了id为:"+id+"的任务";
    }
}


